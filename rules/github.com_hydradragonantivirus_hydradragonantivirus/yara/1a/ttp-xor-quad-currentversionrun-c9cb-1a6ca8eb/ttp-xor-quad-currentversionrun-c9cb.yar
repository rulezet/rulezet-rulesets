rule TTP_XOR_QUAD_CurrentVersionRun_c9cb {
  strings:
    $key_c9cb = { 9a a4 [2] be aa [2] 95 86 [2] bb a4 [2] af bf [2] a0 a5 [2] be b8 [2] bc b9 [2] a7 bf [2] bb b8 [2] a7 97 }

  condition:
    any of them
}