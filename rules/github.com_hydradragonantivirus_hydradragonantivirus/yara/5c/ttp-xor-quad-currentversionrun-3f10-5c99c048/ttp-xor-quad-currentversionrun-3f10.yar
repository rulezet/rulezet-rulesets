rule TTP_XOR_QUAD_CurrentVersionRun_3f10 {
  strings:
    $key_3f10 = { 6c 7f [2] 48 71 [2] 63 5d [2] 4d 7f [2] 59 64 [2] 56 7e [2] 48 63 [2] 4a 62 [2] 51 64 [2] 4d 63 [2] 51 4c }

  condition:
    any of them
}