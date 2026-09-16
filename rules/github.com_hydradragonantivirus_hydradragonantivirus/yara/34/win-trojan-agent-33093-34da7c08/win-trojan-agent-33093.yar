rule Win_Trojan_Agent_33093
{
strings:
	$a0 = { 927dc0cada10e558091d3c2a0df02418df27129c3e74984d65f9fad20e463f804f5bd5e1eb4d45dba2eed56e4efbf47b3aed9faf906b8eaad9ca53154e156c030d18b357b716 }


condition:
	$a0
}