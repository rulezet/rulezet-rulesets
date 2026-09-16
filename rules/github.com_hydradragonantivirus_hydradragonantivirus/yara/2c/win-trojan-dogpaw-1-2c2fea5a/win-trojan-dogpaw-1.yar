rule Win_Trojan_DogPaw_1
{
strings:
	$a0 = { af306a04bfd003cd21fc5e04518bee74111ee898ff8c5af9ab5893abb8a903e86000578e5e3846392c73fb8d325aac }


condition:
	$a0
}