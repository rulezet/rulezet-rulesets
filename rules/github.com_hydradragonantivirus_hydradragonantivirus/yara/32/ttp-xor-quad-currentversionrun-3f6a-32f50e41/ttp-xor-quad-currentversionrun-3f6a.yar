rule TTP_XOR_QUAD_CurrentVersionRun_3f6a {
  strings:
    $key_3f6a = { 6c 05 [2] 48 0b [2] 63 27 [2] 4d 05 [2] 59 1e [2] 56 04 [2] 48 19 [2] 4a 18 [2] 51 1e [2] 4d 19 [2] 51 36 }

  condition:
    any of them
}