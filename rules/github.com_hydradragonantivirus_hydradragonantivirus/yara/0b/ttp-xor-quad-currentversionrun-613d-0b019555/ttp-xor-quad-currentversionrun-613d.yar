rule TTP_XOR_QUAD_CurrentVersionRun_613d {
  strings:
    $key_613d = { 32 52 [2] 16 5c [2] 3d 70 [2] 13 52 [2] 07 49 [2] 08 53 [2] 16 4e [2] 14 4f [2] 0f 49 [2] 13 4e [2] 0f 61 }

  condition:
    any of them
}