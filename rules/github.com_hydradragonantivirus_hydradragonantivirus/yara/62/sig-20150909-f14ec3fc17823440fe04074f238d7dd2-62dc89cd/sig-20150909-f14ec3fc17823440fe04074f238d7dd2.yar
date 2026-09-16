rule sig_20150909_f14ec3fc17823440fe04074f238d7dd2 {
  meta:
    description = "datamaliciousorder - file 20150909_f14ec3fc17823440fe04074f238d7dd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4905ce402be6b39ba0d264a7ea2beb653a1e229a83cee1418073df3cf3a49bb"

  strings:
    $x1  = "var NavigatorController=Class.create({initialize:function(a){this.domNode=a;this.thumbnailSidebar=new NavigatorThumbnailSidebar(" ascii
    $s2  = "nailSelection.select(this.selectedSlideIndex)},handleScriptDidDownloadEvent:function(g){var c=g.memo.script;for(var e=0,f=c.slid" ascii
    $s3  = "criptDidDownloadEvent,this.handleScriptDidDownloadEvent.bind(this));this.slideThumbnail=null},initScrollbar:function(){if(this.t" ascii
    $s4  = "ontroller.script.originalSlideHeight;var e=b/f;var c,a;if(e>=4/3){c=88;a=Math.ceil(88*(1/e))}else{c=Math.ceil(66*e);a=66}this.sl" ascii
    $s5  = ".width=\"137px\"}},handleClickEvent:function(b){if(gShowController.isRecording){return}b=b||window.event;var c=b.target||b.srcEl" ascii
    $s6  = ".width+\"px; height:\"+this.slideThumbnail.height+\"px; left:\"+this.slideThumbnail.left+\"px; top:\"+this.slideThumbnail.top+\"" ascii
    $s7  = "ind(this,e,a));a.src=h}else{gShowController.delegate.loadTextureBySlideIndex(e,{type:\"slideThumbnail\",state:\"outgoing\"},(fun" ascii
    $s8  = "Left)-document.documentElement.clientLeft;g=e.clientY+(document.documentElement.scrollTop||document.body.scrollTop)-document.doc" ascii
    $s9  = "umentElement.clientTop}}if(c===0&&g===0){return}var b=this.selectedSlideIndex*76;var f=this.thumbnailScroller.domNode.scrollTop;" ascii
    $s10 = "eftSidebar.domNode,\"mouseover\",this.handleMouseOverEvent.bind(this));Event.observe(this.domNode,\"mouseleave\",this.handleMous" ascii
    $s11 = "+\",0,0)\")}d.setAttribute(\"style\",kTransitionPropertyName+\":opacity; \"+kTransitionDurationName+\":500; width:\"+this.slideT" ascii
    $s12 = "Event.bind(this));document.observe(kSlideIndexDidChangeEvent,this.handleSlideIndexDidChangeEvent.bind(this));document.observe(kS" ascii
    $s13 = ",\"navigatorThumbnailItem\");this.thumbnailContentNode=document.createElement(\"div\");this.thumbnailContentNode.setAttribute(\"" ascii
    $s14 = "var a=this.thumbnailScroller.domNode.clientHeight;if(f>b){this.thumbnailScroller.domNode.scrollTop=b}else{if(f+a<b+76){var d=b-f" ascii
    $s15 = ".pageY){c=e.pageX;g=e.pageY}else{if(e.clientX||e.clientY){c=e.clientX+(document.documentElement.scrollLeft||document.body.scroll" ascii
    $s16 = "t:function(a){clearTimeout(this.navigatorTimeout);this.navigatorTimeout=setTimeout(this.thumbnailSidebar.hide.bind(this.thumbnai" ascii
    $s17 = "26px\"}else{this.thumbnailScroller.domNode.style.width=\"129px\"}if(browserPrefix===\"ms\"){this.domNode.style.width=\"148px\";t" ascii
    $s18 = "n(j,i){this.updateThumbnail(j,i)}).bind(this,e))}}this.initScrollbar()},updateThumbnail:function(g,d){var h=this.thumbnailContai" ascii
    $s19 = ".appendChild(this.leftSidebar.domNode);Event.observe(this.domNode,\"click\",this.handleClickEvent.bind(this));Event.observe(this" ascii
    $s20 = ": 76px;\");this.thumb=document.createElement(\"div\");this.thumb.setAttribute(\"style\",\"position: absolute; top: 4px; width: 9" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}