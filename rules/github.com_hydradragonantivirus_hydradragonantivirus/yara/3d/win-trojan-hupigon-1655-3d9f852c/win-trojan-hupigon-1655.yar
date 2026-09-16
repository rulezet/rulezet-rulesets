rule Win_Trojan_Hupigon_1655
{
strings:
	$a0 = { e3ea30c9bb26643d1efc5416d5a747a3b6adacdcfc6ca79070641498223129d0cc739f43984f8d2d7d8720da94c8bf3b5d3541435576e608b2effc07d64a70f54d }


condition:
	$a0
}