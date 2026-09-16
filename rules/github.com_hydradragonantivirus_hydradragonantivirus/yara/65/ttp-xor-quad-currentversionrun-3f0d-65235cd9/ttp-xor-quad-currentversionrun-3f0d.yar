rule TTP_XOR_QUAD_CurrentVersionRun_3f0d {
  strings:
    $key_3f0d = { 6c 62 [2] 48 6c [2] 63 40 [2] 4d 62 [2] 59 79 [2] 56 63 [2] 48 7e [2] 4a 7f [2] 51 79 [2] 4d 7e [2] 51 51 }

  condition:
    any of them
}