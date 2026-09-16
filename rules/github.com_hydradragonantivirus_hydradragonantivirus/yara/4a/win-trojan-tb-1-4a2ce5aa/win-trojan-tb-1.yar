rule Win_Trojan_TB_1
{
strings:
	$a0 = { 3001cd96cdec5ebe2c01cd96cdec5ecdb2cdb2cdb2be2801cd96cdb8cdb2be2401cd96cdb8cd }


condition:
	$a0
}