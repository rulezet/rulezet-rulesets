rule GravityRAT_G1_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"
		description = "PDB path for Gravity RAT G1"

	strings:
		$PDB1 = "f:\\F\\Windows Work\\G1\\Adeel's Laptop\\G1 Main Virus\\systemInterrupts\\gravity\\obj\\x86\\Debug\\systemInterrupts.pdb"
		$PDB2 = "f:\\F\\Windows Work\\G1\\Adeel's Laptop\\"
       		$PDB3 = "\\gravity\\obj\\x86\\Debug\\"
	condition:
		any of them
}