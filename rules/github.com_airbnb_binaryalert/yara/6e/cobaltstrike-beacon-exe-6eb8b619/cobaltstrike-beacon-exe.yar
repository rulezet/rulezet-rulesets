import "math"
import "pe"
rule cobaltstrike_beacon_exe
{
    condition:
        cobaltstrike_template_exe and
        filesize > 100KB and filesize < 500KB and
        pe.sections[pe.section_index(".data")].raw_data_size > 200000 and
        math.entropy(pe.sections[pe.section_index(".data")].raw_data_offset + 1024, 150000 ) >= 7 
}