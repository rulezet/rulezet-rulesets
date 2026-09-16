rule StarForce_V3_X_DLL____StarForce_Copy_Protection_System
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}