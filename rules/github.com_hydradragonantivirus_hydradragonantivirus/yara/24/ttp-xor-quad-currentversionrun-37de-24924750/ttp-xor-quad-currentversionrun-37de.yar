rule TTP_XOR_QUAD_CurrentVersionRun_37de {
  strings:
    $key_37de = { 64 b1 [2] 40 bf [2] 6b 93 [2] 45 b1 [2] 51 aa [2] 5e b0 [2] 40 ad [2] 42 ac [2] 59 aa [2] 45 ad [2] 59 82 }

  condition:
    any of them
}