rule TTP_XOR_QUAD_CurrentVersionRun_3cfe {
  strings:
    $key_3cfe = { 6f 91 [2] 4b 9f [2] 60 b3 [2] 4e 91 [2] 5a 8a [2] 55 90 [2] 4b 8d [2] 49 8c [2] 52 8a [2] 4e 8d [2] 52 a2 }

  condition:
    any of them
}