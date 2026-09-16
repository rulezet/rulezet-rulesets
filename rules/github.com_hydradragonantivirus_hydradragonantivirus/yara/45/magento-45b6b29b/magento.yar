import "hash"
rule Magento: ECommerce {
  condition:
    
    hash.sha1(0, filesize) == "039ad85dc5940947849f7fe1a179563c829403ab" or      hash.sha1(0, filesize) == "5f577c2a35ababbf39e0efb53294e5adf523822b" or      hash.sha1(0, filesize) == "27f0e4b1a09e816e40f9e6396c2d4a3cabdb2797" or      hash.sha1(0, filesize) == "258522ff97a68138daf0566786b22e722c0ff520" or      hash.sha1(0, filesize) == "a90d7f679a41443d58d5a96bcb369c3196a19538" or      hash.sha1(0, filesize) == "7faa31f0ee66f32a92b5fd516eb65ff4a3603156" or      hash.sha1(0, filesize) == "6b3f32e50343b70138ce4adb73045782b3edd851" or      hash.sha1(0, filesize) == "ea4c5c75dc3e4ed53c6b9dba09ad9d23f10df9d5" or      hash.sha1(0, filesize) == "eb9dd8ec849ef09b63a75b367441a14ca5d5f7ae" or      hash.sha1(0, filesize) == "a52d111efd3b372104ebc139551d2d8516bbf5e0" or  
    
    hash.sha1(0, filesize) == "988006fe987a3c192d74b355a5011326f7728d60" or      hash.sha1(0, filesize) == "0747f27fd0469608d1686abeaf667d9ad2b4c214" or      hash.sha1(0, filesize) == "6c0b33527f8e4b0cab82fc9ba013549f945fad75" or      hash.sha1(0, filesize) == "9a340997bddbee19c1ec9ed62aa3b7e7a39d620a" or      hash.sha1(0, filesize) == "a11e09ee903fe2a1f8188b27186d2dd5098419af" or      hash.sha1(0, filesize) == "c60a936b7a532a171b79e17bfc3497de1e3e25be" or      hash.sha1(0, filesize) == "9947a190e9d82a2e7a887b375f4b67a41349cc7f" or      hash.sha1(0, filesize) == "5fe6024f5c565a7c789de28470b64ce95763e3f4" or  
    
    hash.sha1(0, filesize) == "4fa9deecb5a49b0d5b1f88a8730ce20a262386f7" or      hash.sha1(0, filesize) == "f214646051f5376475d06ef50fe1e5634285ba1b" or  
    
    hash.sha1(0, filesize) == "f46cf6fd47e60e77089d94cca5b89d19458987ca" or      hash.sha1(0, filesize) == "ffb3e46c87e173b1960e50f771954ebb1efda66e" or      hash.sha1(0, filesize) == "7faa31f0ee66f32a92b5fd516eb65ff4a3603156" or      hash.sha1(0, filesize) == "539de72a2a424d86483f461a9e38ee42df158f26" or      hash.sha1(0, filesize) == "6b3f32e50343b70138ce4adb73045782b3edd851" or  
    
    hash.sha1(0, filesize) == "0b74f4b259c63c01c74fb5913c3ada87296107c8" or      hash.sha1(0, filesize) == "951a4639e49c6b2ad8adeb38481e2290297c8e70" or      hash.sha1(0, filesize) == "44ba7a5b685f4a52113559f366aaf6e9a22ae21e"  }