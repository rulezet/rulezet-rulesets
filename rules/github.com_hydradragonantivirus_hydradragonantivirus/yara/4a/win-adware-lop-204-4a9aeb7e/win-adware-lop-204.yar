rule Win_Adware_Lop_204
{
strings:
	$a0 = { cfe7b43f92a5ae97508a6615cb786729b397efde81e8f22ed727ebb729a43830b856f7daf58409820e7de45ea57fb9c214fa3128dc15c68b484e9993 }


condition:
	$a0
}