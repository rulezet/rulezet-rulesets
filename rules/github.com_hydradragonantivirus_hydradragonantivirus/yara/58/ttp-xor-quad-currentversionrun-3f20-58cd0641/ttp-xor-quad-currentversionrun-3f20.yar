rule TTP_XOR_QUAD_CurrentVersionRun_3f20 {
  strings:
    $key_3f20 = { 6c 4f [2] 48 41 [2] 63 6d [2] 4d 4f [2] 59 54 [2] 56 4e [2] 48 53 [2] 4a 52 [2] 51 54 [2] 4d 53 [2] 51 7c }

  condition:
    any of them
}