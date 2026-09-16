rule TTP_XOR_QUAD_CurrentVersionRun_263e {
  strings:
    $key_263e = { 75 51 [2] 51 5f [2] 7a 73 [2] 54 51 [2] 40 4a [2] 4f 50 [2] 51 4d [2] 53 4c [2] 48 4a [2] 54 4d [2] 48 62 }

  condition:
    any of them
}