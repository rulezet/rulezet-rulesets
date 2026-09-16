rule GravityRAT_GX_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"
		description = "PDB path for Gravity RAT GX"

	strings:
		$PDB1 = "C:\\Users\\The Invincible\\Desktop\\gx\\gx-current-program\\LSASS\\obj\\Release\\LSASS.pdb"
		$PDB2 = "C:\\Users\\The Invincible\\D"
       		$PDB3 = "Desktop\\gx\\gx-"
	condition:
		any of them
}