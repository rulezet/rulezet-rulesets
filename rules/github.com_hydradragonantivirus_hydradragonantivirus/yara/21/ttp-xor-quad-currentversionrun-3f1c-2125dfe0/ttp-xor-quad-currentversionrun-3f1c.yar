rule TTP_XOR_QUAD_CurrentVersionRun_3f1c {
  strings:
    $key_3f1c = { 6c 73 [2] 48 7d [2] 63 51 [2] 4d 73 [2] 59 68 [2] 56 72 [2] 48 6f [2] 4a 6e [2] 51 68 [2] 4d 6f [2] 51 40 }

  condition:
    any of them
}