import "pe"
rule _VcasmProtector_11__12__vcasm_
{
	meta:
		description = "Vcasm-Protector 1.1 - 1.2 -> vcasm"
	strings:
		$0 = {EB 0B 5B 56 50 72 6F 74 65 63 74 5D}
	condition:
		$0 at pe.entry_point
}