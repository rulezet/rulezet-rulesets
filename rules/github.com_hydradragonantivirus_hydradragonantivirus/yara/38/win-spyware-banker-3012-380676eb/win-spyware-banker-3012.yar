rule Win_Spyware_Banker_3012
{
strings:
	$a0 = { 4f7e68717542ccfb4dd904365c2f070d12c1e7545777aaf76a5f00d39c1334b6bde06d34aca1bf31383a5f5252d669dcdcb525b4b0035472ee02280c734cee9a1999ade5 }


condition:
	$a0
}