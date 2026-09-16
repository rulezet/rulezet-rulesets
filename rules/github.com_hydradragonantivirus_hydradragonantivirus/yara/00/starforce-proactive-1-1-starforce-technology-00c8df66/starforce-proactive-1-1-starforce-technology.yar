rule StarForce_ProActive_1_1____StarForce_Technology
{
strings:
		$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 57  }

condition:
		$a0 at entrypoint
}