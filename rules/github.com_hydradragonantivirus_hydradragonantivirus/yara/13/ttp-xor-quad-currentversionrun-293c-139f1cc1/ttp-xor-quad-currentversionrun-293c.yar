rule TTP_XOR_QUAD_CurrentVersionRun_293c {
  strings:
    $key_293c = { 7a 53 [2] 5e 5d [2] 75 71 [2] 5b 53 [2] 4f 48 [2] 40 52 [2] 5e 4f [2] 5c 4e [2] 47 48 [2] 5b 4f [2] 47 60 }

  condition:
    any of them
}