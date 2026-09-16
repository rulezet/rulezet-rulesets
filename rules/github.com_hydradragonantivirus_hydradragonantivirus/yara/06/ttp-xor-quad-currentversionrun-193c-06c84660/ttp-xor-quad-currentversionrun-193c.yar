rule TTP_XOR_QUAD_CurrentVersionRun_193c {
  strings:
    $key_193c = { 4a 53 [2] 6e 5d [2] 45 71 [2] 6b 53 [2] 7f 48 [2] 70 52 [2] 6e 4f [2] 6c 4e [2] 77 48 [2] 6b 4f [2] 77 60 }

  condition:
    any of them
}