import "hash"
rule Misc {
  condition:
    
    hash.sha1(0, filesize) == "9452a5f1183cbef0487b922cc1ba904ea21ad39a"
}