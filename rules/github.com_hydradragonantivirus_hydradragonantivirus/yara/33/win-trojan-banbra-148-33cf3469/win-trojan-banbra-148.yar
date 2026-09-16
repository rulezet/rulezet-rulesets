rule Win_Trojan_Banbra_148
{
strings:
	$a0 = { b064013a8e18eaea301088e132d6fa773e3f08689ccbe329ad021fd990bdeba75b2b8efa2957ddb6f7a74ac06784caf2c65520f383b322b10a474f0cae7f849cb965902d241f }


condition:
	$a0
}