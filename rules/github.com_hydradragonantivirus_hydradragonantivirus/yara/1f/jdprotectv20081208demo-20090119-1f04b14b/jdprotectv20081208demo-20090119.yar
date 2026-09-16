import "pe"
rule _JDProtectV20081208demo____20090119_
{
	meta:
		description = "JDProtect.V20081208.demo -> ��������Ƽ� * 20090119"
	strings:
		$0 = {10 3C 0C 32 54 50 50 83 2D 51 52 B9 E8 ?? 52 2A 10 16 84 01}
	condition:
		$0 at pe.entry_point
}