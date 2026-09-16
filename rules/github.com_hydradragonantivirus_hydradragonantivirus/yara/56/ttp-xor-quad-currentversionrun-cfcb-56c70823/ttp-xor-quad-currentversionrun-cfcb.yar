rule TTP_XOR_QUAD_CurrentVersionRun_cfcb {
  strings:
    $key_cfcb = { 9c a4 [2] b8 aa [2] 93 86 [2] bd a4 [2] a9 bf [2] a6 a5 [2] b8 b8 [2] ba b9 [2] a1 bf [2] bd b8 [2] a1 97 }

  condition:
    any of them
}