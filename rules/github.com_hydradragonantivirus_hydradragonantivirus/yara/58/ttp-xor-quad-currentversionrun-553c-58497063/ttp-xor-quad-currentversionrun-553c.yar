rule TTP_XOR_QUAD_CurrentVersionRun_553c {
  strings:
    $key_553c = { 06 53 [2] 22 5d [2] 09 71 [2] 27 53 [2] 33 48 [2] 3c 52 [2] 22 4f [2] 20 4e [2] 3b 48 [2] 27 4f [2] 3b 60 }

  condition:
    any of them
}