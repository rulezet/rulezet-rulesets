rule Win_Trojan_Gothmod_3
{
strings:
	$a0 = { 8c11ba0c010500003b060200722ab409ba1c01cd21b8014ccd214e6f7420656e6f756768206d656d6f7279242020 }


condition:
	$a0
}