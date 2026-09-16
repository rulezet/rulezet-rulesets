rule TTP_XOR_QUAD_CurrentVersionRun_bfcc {
  strings:
    $key_bfcc = { ec a3 [2] c8 ad [2] e3 81 [2] cd a3 [2] d9 b8 [2] d6 a2 [2] c8 bf [2] ca be [2] d1 b8 [2] cd bf [2] d1 90 }

  condition:
    any of them
}