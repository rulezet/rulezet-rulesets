rule TTP_XOR_QUAD_CurrentVersionRun_2e3c {
  strings:
    $key_2e3c = { 7d 53 [2] 59 5d [2] 72 71 [2] 5c 53 [2] 48 48 [2] 47 52 [2] 59 4f [2] 5b 4e [2] 40 48 [2] 5c 4f [2] 40 60 }

  condition:
    any of them
}