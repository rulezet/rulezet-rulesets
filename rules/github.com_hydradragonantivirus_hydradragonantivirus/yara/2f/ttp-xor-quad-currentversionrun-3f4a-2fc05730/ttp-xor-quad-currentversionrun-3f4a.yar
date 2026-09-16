rule TTP_XOR_QUAD_CurrentVersionRun_3f4a {
  strings:
    $key_3f4a = { 6c 25 [2] 48 2b [2] 63 07 [2] 4d 25 [2] 59 3e [2] 56 24 [2] 48 39 [2] 4a 38 [2] 51 3e [2] 4d 39 [2] 51 16 }

  condition:
    any of them
}