rule TTP_XOR_QUAD_CurrentVersionRun_613c {
  strings:
    $key_613c = { 32 53 [2] 16 5d [2] 3d 71 [2] 13 53 [2] 07 48 [2] 08 52 [2] 16 4f [2] 14 4e [2] 0f 48 [2] 13 4f [2] 0f 60 }

  condition:
    any of them
}