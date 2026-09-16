rule TTP_XOR_QUAD_CurrentVersionRun_296d {
  strings:
    $key_296d = { 7a 02 [2] 5e 0c [2] 75 20 [2] 5b 02 [2] 4f 19 [2] 40 03 [2] 5e 1e [2] 5c 1f [2] 47 19 [2] 5b 1e [2] 47 31 }

  condition:
    any of them
}