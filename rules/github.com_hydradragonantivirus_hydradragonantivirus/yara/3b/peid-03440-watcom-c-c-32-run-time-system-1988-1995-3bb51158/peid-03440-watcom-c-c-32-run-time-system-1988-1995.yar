rule PEiD_03440_WATCOM_C_C___32_Run_Time_System_1988_1995_ {
  meta:
    description = "[WATCOM C/C++ 32 Run-Time System 1988-1995]"
    ep_only     = "true"

  strings:
    $a = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 }

  condition:
    $a
}