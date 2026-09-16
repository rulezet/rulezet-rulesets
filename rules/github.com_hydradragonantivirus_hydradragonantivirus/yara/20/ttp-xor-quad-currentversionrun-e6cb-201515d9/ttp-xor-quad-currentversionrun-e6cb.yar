rule TTP_XOR_QUAD_CurrentVersionRun_e6cb {
  strings:
    $key_e6cb = { b5 a4 [2] 91 aa [2] ba 86 [2] 94 a4 [2] 80 bf [2] 8f a5 [2] 91 b8 [2] 93 b9 [2] 88 bf [2] 94 b8 [2] 88 97 }

  condition:
    any of them
}