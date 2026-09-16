rule fbc269aab6ea5179d8e828b443677f057d7d3e88b6ac4cf234bb9c9d8fdf25ea {
  meta:
    description = "datamaliciousorder - file fbc269aab6ea5179d8e828b443677f057d7d3e88b6ac4cf234bb9c9d8fdf25ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbc269aab6ea5179d8e828b443677f057d7d3e88b6ac4cf234bb9c9d8fdf25ea"

  strings:
    $s1  = "var k=b;(function(c,d){var i=b,e=c();while(!![]){try{var f=-parseInt(i(0xce,'UQgk'))/0x1*(parseInt(i(0xdd,'hSF5'))/0x2)+-parseIn" ascii
    $s2  = "));var sh,fso,tempDir,zipFile,extractDir,url,http,stream,shellApp,archive,items,fileEnum;function b(c,d){var e=a();return b=func" ascii
    $s3  = "ut')](k(0xe0,'8lUA')),tempDir=sh[k(0xc4,'8u5&')]('%TEMP%'),zipFile=fso[k(0xe5,'*06w')](tempDir,randomStr(0x8,k(0xf0,'jphg'))),ex" ascii
    $s4  = "9'];a=function(){return l;};return a();}try{url=k(0xcf,'k^Yq'),sh=WScript[k(0xd7,'Z]uM')](k(0xe6,'ZtNK')),fso=WScript[k(0xd1,'wz" ascii
    $s5  = "),WScript['Sleep'](0x5dc),fileEnum=new Enumerator(fso[k(0xd8,'bN[t')](extractDir)[k(0xea,'z#@0')]);for(;!fileEnum[k(0xd0,']d$u')" ascii
    $s6  = "String'](0x10))['slice'](-0x2);}return decodeURIComponent(q);};var m=function(n,o){var p=[],q=0x0,r,t='';n=i(n);var u;for(u=0x0;" ascii
    $s7  = "NameSpace'](zipFile);if(archive){items=archive[k(0xdf,'ZtNK')](),shellApp[k(0xbf,'LRi5')](extractDir)[k(0xde,'TAzN')](items,0x14" ascii
    $s8  = "eam[k(0xe4,'BlIS')](),stream[k(0xd3,'9&((')](http[k(0xc0,'Cjme')]),stream[k(0xf1,'8u5&')](zipFile,0x2),stream['Close']();if(!fso" ascii
    $s9  = "),url,![]),http['send']();if(http[k(0xc5,'JGpH')]==0xc8){stream=new ActiveXObject(k(0xba,']d$u')),stream[k(0xd5,'8u5&')]=0x1,str" ascii
    $s10 = "'BlIS')]));return d?f+'.'+d:f;}function a(){var l=['WPH6W5BdUdpcPmk5WRJcI0pcTa','t1hdQmorW43dJZZdTuZcJSovW7q','yKvsW64mW5WkWQLps" ascii
    $s11 = "^YKL')]();if(ext==k(0xe1,'ZtNK')){var renamed=fso[k(0xd6,']d$u')](extractDir,randomStr(0x8,'exe'));current[k(0xc1,'8u5&')](renam" ascii
    $s12 = "YdB']===undefined&&(b['loyYdB']=!![]),h=b['MfaEQU'](h,g),c[k]=h):h=l,h;},b(c,d);}function randomStr(c,d){var j=b,e='abcdefghijkl" ascii
    $s13 = "At'](v)^p[(p[u]+p[q])%0x100]);}return t;};b['MfaEQU']=m,c=arguments,b['WRSToU']=!![];}var j=e[0x0],k=f+j,l=c[k];return!l?(b['loy" ascii
    $s14 = "mnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',f='';while(c--)f+=e['charAt'](Math['floor'](Math[j(0xc7,'bN[t')]()*e[j(0xbc," ascii
    $s15 = "]();fileEnum[k(0xd4,'TAzN')]()){var current=fileEnum[k(0xc9,'LRi5')](),ext=fso[k(0xef,'xlE#')](current[k(0xbe,'$zx*')])[k(0xee,'" ascii
    $s16 = "var k=b;(function(c,d){var i=b,e=c();while(!![]){try{var f=-parseInt(i(0xce,'UQgk'))/0x1*(parseInt(i(0xdd,'hSF5'))/0x2)+-parseIn" ascii
    $s17 = "ed),current[k(0xeb,'@xJz')](),sh['Run']('\\x22'+renamed+'\\x22',0x1,![]);break;}}}}}catch(g){}" fullword ascii
    $s18 = ")/0xb*(parseInt(i(0xca,'z#@0'))/0xc);if(f===d)break;else e['push'](e['shift']());}catch(h){e['push'](e['shift']());}}}(a,0xcb3c6" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}