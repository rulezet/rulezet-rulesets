rule StarForce_3_0____StarForce_Technology
{
strings:
		$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 63  }

condition:
		$a0 at entrypoint
}