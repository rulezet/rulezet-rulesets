rule Win_Trojan_VGEN_183
{
strings:
	$a0 = { ffb500b600e871ff5b07b601b527e868ff59e2dcc380fa03770a80fc02720580fc047603e966ff1e0e1f882675008c }


condition:
	$a0
}