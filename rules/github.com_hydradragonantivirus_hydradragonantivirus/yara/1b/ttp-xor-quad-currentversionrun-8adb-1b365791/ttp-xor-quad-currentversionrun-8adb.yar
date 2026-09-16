rule TTP_XOR_QUAD_CurrentVersionRun_8adb {
  strings:
    $key_8adb = { d9 b4 [2] fd ba [2] d6 96 [2] f8 b4 [2] ec af [2] e3 b5 [2] fd a8 [2] ff a9 [2] e4 af [2] f8 a8 [2] e4 87 }

  condition:
    any of them
}