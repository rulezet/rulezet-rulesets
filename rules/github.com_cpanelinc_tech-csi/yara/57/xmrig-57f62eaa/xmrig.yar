rule XMRig {
   meta:
      attack = "T1496"
      description = "Detects XMRig miner"
   strings:
      $ = "password for mining server" nocase wide ascii
      $ = "threads count to initialize RandomX dataset" nocase wide ascii
      $ = "display this help and exit" nocase wide ascii
      $ = "maximum CPU threads count (in percentage) hint for autoconfig" nocase wide ascii
      $ = "enable CUDA mining backend" nocase wide ascii
      $ = "cryptonight" nocase wide ascii
   condition:
      5 of them
}