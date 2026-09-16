import "pe"
rule _IDA_Interactive_Disassembler_database_
{
	meta:
		description = "IDA (Interactive Disassembler) database"
	strings:
		$0 = {49 44 41}
	condition:
		$0 at pe.entry_point
}