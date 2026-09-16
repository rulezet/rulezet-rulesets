rule TTP_XOR_QUAD_CurrentVersionRun_202e {
  strings:
    $key_202e = { 73 41 [2] 57 4f [2] 7c 63 [2] 52 41 [2] 46 5a [2] 49 40 [2] 57 5d [2] 55 5c [2] 4e 5a [2] 52 5d [2] 4e 72 }

  condition:
    any of them
}