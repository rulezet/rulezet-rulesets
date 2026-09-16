rule TTP_XOR_QUAD_CurrentVersionRun_297e {
  strings:
    $key_297e = { 7a 11 [2] 5e 1f [2] 75 33 [2] 5b 11 [2] 4f 0a [2] 40 10 [2] 5e 0d [2] 5c 0c [2] 47 0a [2] 5b 0d [2] 47 22 }

  condition:
    any of them
}