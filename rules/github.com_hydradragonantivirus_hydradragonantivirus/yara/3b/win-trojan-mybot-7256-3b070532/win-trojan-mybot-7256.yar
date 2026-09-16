rule Win_Trojan_Mybot_7256
{
strings:
	$a0 = { 0f84facace4de52f5747de5e01df04f7cfe1b25768cb9c5b9ec82da453fa944e580907fbad4361021be88c8adf0fceea86cd48f4e55c3d8ae3a0e39498c1fc51f4ed87fc1a6295a6273159346701 }


condition:
	$a0
}