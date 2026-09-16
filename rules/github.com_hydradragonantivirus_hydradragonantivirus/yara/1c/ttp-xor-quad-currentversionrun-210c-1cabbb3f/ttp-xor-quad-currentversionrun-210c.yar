rule TTP_XOR_QUAD_CurrentVersionRun_210c {
  strings:
    $key_210c = { 72 63 [2] 56 6d [2] 7d 41 [2] 53 63 [2] 47 78 [2] 48 62 [2] 56 7f [2] 54 7e [2] 4f 78 [2] 53 7f [2] 4f 50 }

  condition:
    any of them
}