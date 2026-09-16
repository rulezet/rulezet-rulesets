rule Win_Trojan_Bowl_9
{
strings:
	$a0 = { 81ed06013ec686130101b800003d01007503e9bb02e8a702e88c023ec6861301008db65a03bf0001a5a48d963c04 }


condition:
	$a0
}