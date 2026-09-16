rule sig_20150909_32b17d21e132ee5906f5ac98b2c18cd2 {
  meta:
    description = "datamaliciousorder - file 20150909_32b17d21e132ee5906f5ac98b2c18cd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e788f66a850c59c93ecdd26dad8965a58607703fe1cf2c026557ff091a787189"

  strings:
    $x1  = "var kShowSizeDidChangeEvent=\"ScriptManager:ShowSizeDidChangeEvent\";var kScriptDidDownloadEvent=\"ScriptManager:ScriptDidDownlo" ascii
    $x2  = "ead.appendChild(a)}else{new Ajax.Request(c,{method:\"get\",onSuccess:this.scriptDidDownload.bind(this),onFailure:this.scriptDidN" ascii
    $s3  = "Show());if(this.script==null){debugMessageAlways(kDebugScriptMangaer_DownloadScript,\"An error occured on the server. KPF header" ascii
    $s4  = "JSON.parse(b.responseText)}this.slideManager=new SlideManager({header:this.script});this.slideManager.downloadSlides(this.script" ascii
    $s5  = "Download.bind(this)})}},scriptDidDownload:function(b,a){clearTimeout(this.downloadTimeout);if(a){this.script=b}else{this.script=" ascii
    $s6  = "unction(d){this.scriptDidDownload(d,true)}).bind(this);var a=document.createElement(\"script\");a.setAttribute(\"src\",c);docume" ascii
    $s7  = "[0].animations.push(e)}}break;default:break}},handleSlideDidNotDownloadEvent:function(a){this.scriptDidNotDownload.bind(this)},r" ascii
    $s8  = "t,this.delegate);return}this.downloadTimeout=setTimeout(this.scriptDidNotDownload.bind(this),kMaxScriptDownloadWaitTime);this.do" ascii
    $s9  = "st.length)){return -1}return this.script.sceneIndexFromSlideIndexLookup[a]},slideIndexFromSceneIndex:function(a){if((this.script" ascii
    $s10 = "nt.getElementsByTagName(\"head\")[0].appendChild(c)}else{this.getFontFamilyDefinitionsCssString()}document.fire(kScriptDidDownlo" ascii
    $s11 = "==null)||(a<0)||(a>=this.script.events.length)){return -1}return this.script.slideIndexFromSceneIndexLookup[a]}});" fullword ascii
    $s12 = "is.slideManager.slides[m].downloaded){l=false;break}}}if(l){this.script.events=[];this.script.originalEvents=[];this.script.slid" ascii
    $s13 = "wnloadAlreadyFailed=false;var c=this.showUrl+\"header.json\";if(window.location.protocol===\"file:\"){c=c+\"p\";window.local_hea" ascii
    $s14 = "fire(kScriptDidNotDownloadEvent,{})},sceneIndexFromSlideIndex:function(a){if((this.script==null)||(a<0)||(a>=this.script.slideLi" ascii
    $s15 = "function(a){this.script=null;this.showUrl=a;this.slideManager=null;document.observe(kSlideDidDownloadEvent,this.handleSlideDidDo" ascii
    $s16 = "t:function(b){this.delegate=b;if(this.delegate.getKPFJsonStringForShow){this.script=JSON.parse(this.delegate.getKPFJsonStringFor" ascii
    $s17 = "is.script.slideHeight})}},getFontFamilyDefinitionsCssString:function(){if(typeof(GSFT)===\"undefined\"){GSFT={}}GSFT.FontFamilyD" ascii
    $s18 = ".slideList)},scriptDidNotDownload:function(a){this.downloadAlreadyFailed=true;if(a){clearTimeout(this.downloadTimeout)}document." ascii
    $s19 = "json is null.\");return}this.slideManager=new SlideManager({header:this.script});this.slideManager.getSlides(this.script.slideLi" ascii
    $s20 = "eTextNode(g));document.getElementsByTagName(\"head\")[0].appendChild(c)};(function(){var a=document.createElement(\"script\");a." ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}