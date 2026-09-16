rule TTP_XOR_QUAD_CurrentVersionRun_296c {
  strings:
    $key_296c = { 7a 03 [2] 5e 0d [2] 75 21 [2] 5b 03 [2] 4f 18 [2] 40 02 [2] 5e 1f [2] 5c 1e [2] 47 18 [2] 5b 1f [2] 47 30 }

  condition:
    any of them
}