rule Win_Trojan_Gergana_13
{
strings:
	$a0 = { 580150c7062c020000ba80ffb41acd21bafd02b82425cd21b92300ba5201b44ecd2172742ea0a4ff3c447419ba9effe88d01b8023dcd21720c93e89501e84b }


condition:
	$a0
}