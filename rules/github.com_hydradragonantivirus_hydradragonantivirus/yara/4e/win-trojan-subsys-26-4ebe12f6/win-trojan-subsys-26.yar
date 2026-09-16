rule Win_Trojan_Subsys_26
{
strings:
	$a0 = { e80969e0458aa3c5a40bb17f9849dfe15f30cb7f8cb2425686477f3ef27ce77ab0dc057f708ed69955d052f35406a3e7 }


condition:
	$a0
}